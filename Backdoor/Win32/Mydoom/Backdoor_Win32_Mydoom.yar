
rule Backdoor_Win32_Mydoom{
	meta:
		description = "Backdoor:Win32/Mydoom,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0a 00 53 00 00 03 00 "
		
	strings :
		$a_00_0 = {66 75 76 7a 74 6e 63 76 2e 71 79 79 } //02 00  fuvztncv.qyy
		$a_00_1 = {73 68 69 6d 67 61 70 69 2e 64 6c 6c } //03 00  shimgapi.dll
		$a_00_2 = {46 62 73 67 6a 6e 65 72 5c 5a 76 70 65 62 66 62 73 67 5c 4a 76 61 71 62 6a 66 5c 50 68 65 65 72 61 67 49 72 65 66 76 62 61 5c 52 6b 63 79 62 65 72 65 5c 50 62 7a 51 79 74 33 32 5c 49 72 65 66 76 62 61 } //02 00  Fbsgjner\Zvpebfbsg\Jvaqbjf\PheeragIrefvba\Rkcybere\PbzQyt32\Irefvba
		$a_00_3 = {7a 69 6e 63 69 74 65 } //03 00  zincite
		$a_00_4 = {56 61 67 72 65 61 72 67 54 72 67 50 62 61 61 72 70 67 72 71 46 67 6e 67 72 } //03 00  VagreargTrgPbaarpgrqFgngr
		$a_00_5 = {6a 76 61 76 61 72 67 2e 71 79 79 20 } //03 00  jvavarg.qyy 
		$a_00_6 = {6a 76 61 6e 7a 63 35 } //03 00  jvanzc5
		$a_00_7 = {6a 6a 6a 2e 7a 76 70 65 62 66 62 73 67 2e 70 62 7a } //02 00  jjj.zvpebfbsg.pbz
		$a_00_8 = {30 2e 30 2e 30 2e 30 20 77 77 77 2e 6d 69 63 72 6f 73 6f 66 74 2e 63 6f 6d } //03 00  0.0.0.0 www.microsoft.com
		$a_00_9 = {4b 48 55 44 54 4f 43 2e 53 44 61 52 58 4c 2e 4d 53 44 42 4b 48 55 44 54 4f 43 2e 53 44 61 42 4e 4c } //02 00  KHUDTOC.SDaRXL.MSDBKHUDTOC.SDaBNL
		$a_00_10 = {56 56 56 61 4c 42 2e 45 44 44 61 42 4e 4c } //03 00  VVVaLB.EDDaBNL
		$a_00_11 = {46 62 73 67 6a 6e 65 72 5c 58 6e 6d 6e 6e 5c 47 65 6e 61 66 73 72 65 } //03 00  Fbsgjner\Xnmnn\Genafsre
		$a_00_12 = {46 62 73 67 6a 6e 65 72 5c 5a 76 70 65 62 66 62 73 67 5c 4a 76 61 71 62 6a 66 5c 50 68 65 65 72 61 67 49 72 65 66 76 62 61 5c 45 68 61 } //04 00  Fbsgjner\Zvpebfbsg\Jvaqbjf\PheeragIrefvba\Eha
		$a_00_13 = {46 62 73 67 6a 6e 65 72 5c 5a 76 70 65 62 66 62 73 67 5c 4a 4e 4f 5c 4a 4e 4f 34 5c 4a 6e 6f 20 53 76 79 72 20 41 6e 7a 72 } //03 00  Fbsgjner\Zvpebfbsg\JNO\JNO4\Jno Svyr Anzr
		$a_00_14 = {46 62 73 67 6a 6e 65 72 5c 5a 76 70 65 62 66 62 73 67 5c 56 61 67 72 65 61 72 67 20 4e 70 70 62 68 61 67 20 5a 6e 61 6e 74 72 65 5c 4e 70 70 62 68 61 67 66 } //03 00  Fbsgjner\Zvpebfbsg\Vagrearg Nppbhag Znantre\Nppbhagf
		$a_00_15 = {46 5a 47 43 20 46 72 65 69 72 65 } //01 00  FZGC Freire
		$a_00_16 = {53 4d 54 50 20 44 69 73 70 6c 61 79 20 4e 61 6d 65 } //01 00  SMTP Display Name
		$a_00_17 = {6d 78 2e 25 73 } //01 00  mx.%s
		$a_01_18 = {49 45 46 72 61 6d 65 } //01 00  IEFrame
		$a_00_19 = {41 54 48 5f 4e 6f 74 65 } //02 00  ATH_Note
		$a_00_20 = {72 63 74 72 6c 5f 72 65 6e 77 6e 64 33 32 } //01 00  rctrl_renwnd32
		$a_00_21 = {5c 64 72 69 76 65 72 73 5c 65 74 63 5c 68 6f 73 74 73 } //01 00  \drivers\etc\hosts
		$a_00_22 = {44 6e 73 51 75 65 72 79 5f 41 } //02 00  DnsQuery_A
		$a_00_23 = {20 20 20 20 20 20 20 20 20 20 20 20 2e 70 69 66 } //01 00              .pif
		$a_00_24 = {74 68 65 20 61 74 74 61 63 68 65 64 20 66 69 6c 65 20 66 6f 72 20 64 65 74 61 69 6c 73 } //01 00  the attached file for details
		$a_00_25 = {73 6f 66 74 77 61 72 65 5c 6d 69 63 72 6f 73 6f 66 74 5c 77 61 62 5c 77 61 62 34 5c 77 61 62 } //01 00  software\microsoft\wab\wab4\wab
		$a_00_26 = {64 6f 63 75 6d 65 6e 74 2e 7a 69 70 } //03 00  document.zip
		$a_00_27 = {45 50 43 47 20 47 42 3a 3c 25 66 3e } //02 00  EPCG GB:<%f>
		$a_00_28 = {32 32 30 20 42 6f 74 20 53 65 72 76 65 72 20 28 57 69 6e 33 32 29 } //03 00  220 Bot Server (Win32)
		$a_00_29 = {5a 4e 56 59 20 53 45 42 5a 3a 3c 25 66 3e } //03 00  ZNVY SEBZ:<%f>
		$a_00_30 = {50 62 61 67 72 61 67 2d 51 76 66 63 62 66 76 67 76 62 61 3a 20 6e 67 67 6e 70 75 7a 72 61 67 3b } //01 00  Pbagrag-Qvfcbfvgvba: nggnpuzrag;
		$a_00_31 = {2b 2b 2b 20 41 74 74 61 63 68 6d 65 6e 74 3a 20 4e 6f 20 56 69 72 75 73 20 66 6f 75 6e 64 } //02 00  +++ Attachment: No Virus found
		$a_00_32 = {68 74 74 70 3a 2f 2f 77 77 77 2e 67 6f 6f 67 6c 65 2e 63 6f 6d 2f 73 65 61 72 63 68 3f 68 6c 3d 65 6e 26 69 65 3d 55 54 46 2d 38 26 6f 65 3d 55 54 46 2d 38 26 71 3d 25 73 } //02 00  http://www.google.com/search?hl=en&ie=UTF-8&oe=UTF-8&q=%s
		$a_00_33 = {46 4f 52 20 2f 4c 20 25 25 49 20 49 4e 20 28 31 2c 31 2c 31 30 30 30 30 29 20 44 4f 20 63 3a } //01 00  FOR /L %%I IN (1,1,10000) DO c:
		$a_00_34 = {5b 2d 3d 20 53 6d 61 73 68 20 3d 2d 5d } //02 00  [-= Smash =-]
		$a_00_35 = {54 53 5f 52 4e 44 5f 46 52 4f 4d 5f 44 4f 4d 41 49 4e } //02 00  TS_RND_FROM_DOMAIN
		$a_00_36 = {54 53 5f 53 45 4e 44 45 52 5f 44 4f 4d 41 49 4e } //01 00  TS_SENDER_DOMAIN
		$a_00_37 = {53 59 53 54 45 4d 5c 43 75 72 72 65 6e 74 43 6f 6e 74 72 6f 6c 53 65 74 5c 53 65 72 76 69 63 65 73 5c 53 68 61 72 65 64 41 63 63 65 73 73 5c 50 61 72 61 6d 65 74 65 72 73 5c 46 69 72 65 77 61 6c 6c 50 6f 6c 69 63 79 5c 53 74 61 6e 64 61 72 64 50 72 6f 66 69 6c 65 5c 41 75 74 68 6f 72 69 7a 65 64 41 70 70 6c 69 63 61 74 69 6f 6e 73 5c 4c 69 73 74 } //02 00  SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile\AuthorizedApplications\List
		$a_00_38 = {74 6f 20 6e 65 74 73 6b 79 27 73 20 63 72 65 61 74 6f 72 28 73 29 3a 20 69 6d 68 6f 2c 20 73 6b 79 6e 65 74 } //02 00  to netsky's creator(s): imho, skynet
		$a_00_39 = {63 3a 5c 66 65 65 64 6c 69 73 74 } //01 00  c:\feedlist
		$a_00_40 = {4e 65 74 42 69 6f 73 20 45 78 74 } //02 00  NetBios Ext
		$a_00_41 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 4f 75 74 6c 6f 6f 6b 5c 4f 4d 49 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //02 00  Software\Microsoft\Office\Outlook\OMI Account Manager\Accounts
		$a_00_42 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 4f 66 66 69 63 65 5c 4f 75 74 6c 6f 6f 6b 5c 4f 4d 49 20 41 63 63 6f 75 6e 72 6f 73 6f 66 74 5c 57 41 42 5c 57 41 42 34 5c 57 61 62 20 46 69 6c 65 20 4e 61 6d 65 } //01 00  Software\Microsoft\Office\Outlook\OMI Accounrosoft\WAB\WAB4\Wab File Name
		$a_00_43 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 49 6e 74 65 72 6e 65 74 20 41 63 63 6f 75 6e 74 20 4d 61 6e 61 67 65 72 5c 41 63 63 6f 75 6e 74 73 } //01 00  Software\Microsoft\Internet Account Manager\Accounts
		$a_00_44 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 41 70 70 20 50 61 74 68 73 5c 49 43 51 2e 65 78 65 } //02 00  SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ICQ.exe
		$a_00_45 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 43 6f 6d 44 6c 67 33 32 } //01 00  Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32
		$a_00_46 = {52 43 50 54 20 54 4f 3a 3c 25 73 3e 32 } //03 00  RCPT TO:<%s>2
		$a_00_47 = {74 4e 45 53 56 2e 51 44 2c 6e 48 42 51 4e 52 4e 45 53 2c 78 48 4d 43 4e 56 52 2c 64 54 51 51 44 4d 53 77 44 51 52 48 4e 4d 2c 66 57 4f 4b 4e 51 44 51 2c 74 47 44 4b 4b 74 4c 2e 52 } //03 00  tNESV.QD,nHBQNRNES,xHMCNVR,dTQQDMSwDQRHNM,fWOKNQDQ,tGDKKtL.R
		$a_00_48 = {6e 44 52 23 56 53 44 4b 56 } //02 00  nDR#VSDKV
		$a_00_49 = {4d 65 73 23 77 74 65 6c 77 } //03 00  Mes#wtelw
		$a_00_50 = {4b 52 2e 52 51 55 61 44 57 44 } //03 00  KR.RQUaDWD
		$a_00_51 = {74 4e 45 53 56 2e 51 44 2c 6e 48 42 51 4e 52 4e 45 53 2c 78 48 4d 43 4e 56 52 2c 64 54 51 51 44 4d 53 77 44 51 52 48 4e 4d 2c 73 54 4d } //03 00  tNESV.QD,nHBQNRNES,xHMCNVR,dTQQDMSwDQRHNM,sTM
		$a_00_52 = {74 4e 45 53 56 2e 51 44 2c 6e 48 42 51 4e 52 4e 45 53 2c 78 48 4d 43 4e 56 52 20 6f 75 2c 64 54 51 51 44 4d 53 77 44 51 52 48 4e 4d 2c 78 48 4d 4b 4e 46 4e 4d } //04 00  tNESV.QD,nHBQNRNES,xHMCNVR ou,dTQQDMSwDQRHNM,xHMKNFNM
		$a_00_53 = {43 51 48 55 44 51 52 2c 44 53 42 2c 47 4e 52 53 52 61 } //03 00  CQHUDQR,DSB,GNRSRa
		$a_00_54 = {74 4e 45 53 56 2e 51 44 2c 6c 2e 59 2e 2e 2c 75 51 2e 4d 52 45 44 51 } //03 00  tNESV.QD,l.Y..,uQ.MREDQ
		$a_00_55 = {47 52 44 51 55 61 52 58 52 } //03 00  GRDQUaRXR
		$a_00_56 = {6a 4d 53 44 51 4d 44 53 68 44 53 64 4e 4d 4d 44 42 53 44 43 74 53 2e 53 44 } //02 00  jMSDQMDShDSdNMMDBSDCtS.SD
		$a_00_57 = {25 73 2c 20 25 75 20 25 73 20 25 75 20 25 2e 32 75 3a 25 2e 32 75 3a 25 2e 32 75 20 25 63 25 2e 32 75 25 2e 32 75 } //01 00  %s, %u %s %u %.2u:%.2u:%.2u %c%.2u%.2u
		$a_00_58 = {53 44 45 2b 48 4f 4f 4b 4c 49 42 20 44 65 6d 6f } //01 00  SDE+HOOKLIB Demo
		$a_00_59 = {2a 2a 2a 20 77 73 6f 63 6b 33 32 2e 64 6c 6c 3a 3a 63 6f 6e 6e 65 63 74 2f 73 65 6e 64 28 29 20 61 70 69 20 66 75 6e 63 74 69 6f 6e 73 20 61 72 65 20 6e 6f 77 20 68 6f 6f 6b 65 64 20 2a 2a 2a } //01 00  *** wsock32.dll::connect/send() api functions are now hooked ***
		$a_00_60 = {69 6e 6a 65 63 74 65 64 5f 76 61 20 3d 20 30 78 25 30 38 58 20 3d 20 30 78 25 30 38 58 } //01 00  injected_va = 0x%08X = 0x%08X
		$a_00_61 = {53 74 72 69 6e 67 54 61 62 6c 65 20 3d 20 30 78 25 30 38 58 20 3d 20 30 78 25 30 38 58 } //01 00  StringTable = 0x%08X = 0x%08X
		$a_00_62 = {63 3a 5c 53 4f 43 4b 45 54 68 6f 6f 6b 2e 6c 6f 67 } //01 00  c:\SOCKEThook.log
		$a_00_63 = {5b 78 5d 20 69 6e 6a 65 63 74 65 64 20 74 6f 20 28 25 73 29 } //02 00  [x] injected to (%s)
		$a_00_64 = {5b 78 5d 20 64 6f 6e 65 20 73 79 73 74 65 6d 20 77 69 64 65 20 69 6e 6a 65 63 74 69 6f 6e } //02 00  [x] done system wide injection
		$a_00_65 = {48 2d 45 2d 4c 2d 4c 2d 42 2d 4f 2d 54 2d 50 2d 4f 2d 4c 2d 59 2d 4d 2d 4f 2d 52 2d 50 2d 48 } //02 00  H-E-L-L-B-O-T-P-O-L-Y-M-O-R-P-H
		$a_00_66 = {54 68 65 20 73 6f 75 72 63 65 20 6f 66 20 74 68 69 73 20 77 6f 72 6d 20 68 61 73 20 62 65 65 6e 20 72 65 6c 65 61 73 65 64 20 74 6f 20 70 75 62 6c 69 63 2e 20 69 72 63 20 73 65 72 76 65 72 3a 20 69 72 63 2e 70 6f 77 65 72 69 72 63 2e 6e 65 74 20 23 63 63 70 6f 77 65 72 } //02 00  The source of this worm has been released to public. irc server: irc.powerirc.net #ccpower
		$a_00_67 = {5b 78 5d 20 73 74 61 72 74 69 6e 67 20 48 65 6c 6c 42 6f 74 3a 3a 76 33 20 62 65 74 61 32 } //03 00  [x] starting HellBot::v3 beta2
		$a_00_68 = {2b c2 83 c0 0d 99 b9 1a 00 00 00 f7 f9 8a 44 15 } //01 00 
		$a_00_69 = {8b 45 f8 99 b9 3c 00 00 00 f7 f9 52 8b 45 f8 99 b9 3c 00 00 00 f7 f9 50 } //01 00 
		$a_00_70 = {41 62 67 76 70 72 3a 20 2a 2a 59 6e 66 67 20 4a 6e 65 61 76 61 74 2a 2a } //01 00  Abgvpr: **Ynfg Jneavat**
		$a_00_71 = {4c 62 68 65 20 72 7a 6e 76 79 20 6e 70 70 62 68 61 67 } //01 00  Lbhe rznvy nppbhag
		$a_00_72 = {41 62 67 76 70 72 3a 2a 2a 2a 4c 62 68 65 20 72 7a 6e 76 79 20 6e 70 70 62 68 61 67 20 6a 76 79 79 20 6f 72 20 66 68 66 63 72 61 71 72 71 2a 2a 2a } //01 00  Abgvpr:***Lbhe rznvy nppbhag jvyy or fhfcraqrq***
		$a_00_73 = {46 72 70 68 65 76 67 6c 20 7a 72 6e 66 68 65 72 66 } //01 00  Frphevgl zrnfherf
		$a_00_74 = {52 7a 6e 76 79 20 4e 70 70 62 68 61 67 20 46 68 66 63 72 61 66 76 62 61 } //01 00  Rznvy Nppbhag Fhfcrafvba
		$a_00_75 = {2a 56 5a 43 42 45 47 4e 41 47 2a } //01 00  *VZCBEGNAG*
		$a_00_76 = {50 62 61 67 72 61 67 2d 47 6c 63 72 3a } //01 00  Pbagrag-Glcr:
		$a_00_77 = {4b 2d 43 65 76 62 65 76 67 6c 3a } //01 00  K-Cevbevgl:
		$a_00_78 = {4b 2d 5a 46 5a 6e 76 79 2d 43 65 76 62 65 76 67 6c 3a } //01 00  K-ZFZnvy-Cevbevgl:
		$a_00_79 = {70 75 6e 65 66 72 67 3d } //01 00  punefrg=
		$a_00_80 = {50 62 61 67 72 61 67 2d 47 65 6e 61 66 73 72 65 } //01 00  Pbagrag-Genafsre
		$a_00_81 = {61 6e 7a 72 3d 22 25 66 22 } //01 00  anzr="%f"
		$a_00_82 = {50 62 61 67 72 61 67 2d 51 76 66 63 62 66 76 67 76 62 61 3a } //00 00  Pbagrag-Qvfcbfvgvba:
	condition:
		any of ($a_*)
 
}