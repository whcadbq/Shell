
// ShellDlg.cpp: 实现文件
//


#include "framework.h"
#include "Shell.h"
#include "ShellDlg.h"
#include "afxdialogex.h"
#include "CPacker.h"
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
#pragma warning(disable : 4996)
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
public:

};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)

END_MESSAGE_MAP()


// CShellDlg 对话框



CShellDlg::CShellDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_SHELL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CShellDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CShellDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(BTN_DEC, &CShellDlg::OnBnClickedDec)
	ON_BN_CLICKED(BTN_ADD, &CShellDlg::OnBnClickedAdd)
END_MESSAGE_MAP()


// CShellDlg 消息处理程序

BOOL CShellDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CShellDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CShellDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CShellDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}


//加壳
void CShellDlg::OnBnClickedAdd()
{
	CString strPath;
	GetDlgItemText(FILE_PATH, strPath);
	if (strPath.IsEmpty())
	{
		AfxMessageBox("请输入");
	}
	CPacker cp;
	CString strFlag = strPath.Right(strPath.GetLength()-strPath.ReverseFind('.') - 1);
	if (strFlag.CompareNoCase("EXE")==0)
	{
		if (cp.AddShell(strPath))
		{
			AfxMessageBox("加壳成功");
		}
	}
	else if (strFlag.CompareNoCase("DLL")==0)
	{
		if (cp.AddDllShell(strPath))
		{
			AfxMessageBox("加壳成功");
		}
	}
}

void CShellDlg::OnBnClickedDec()
{
	CString strPath;
	GetDlgItemText(FILE_PATH, strPath);
	if (strPath.IsEmpty())
	{
		AfxMessageBox("请输入");
	}
	CPacker cp;
	if (cp.DecShell(strPath))
	{
		AfxMessageBox("脱壳成功");
	}

}



