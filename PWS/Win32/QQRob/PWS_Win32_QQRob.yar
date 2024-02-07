
rule PWS_Win32_QQRob{
	meta:
		description = "PWS:Win32/QQRob,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 08 00 12 00 00 03 00 "
		
	strings :
		$a_00_0 = {51 51 52 6f 62 62 65 72 } //02 00  QQRobber
		$a_00_1 = {56 43 4d 70 58 3f 64 6b 47 73 59 73 59 6e 75 5f 56 52 4d 71 47 62 75 61 59 3e 79 5d 58 73 3c 6b 55 73 49 69 47 72 61 6c 47 62 41 6f 58 3c } //02 00  VCMpX?dkGsYsYnu_VRMqGbuaY>y]Xs<kUsIiGralGbAoX<
		$a_00_2 = {61 6c 61 32 71 71 00 } //02 00 
		$a_00_3 = {46 44 38 31 46 41 42 41 35 31 32 43 34 39 34 34 34 38 46 31 45 34 41 41 36 34 37 43 36 31 31 42 } //02 00  FD81FABA512C494448F1E4AA647C611B
		$a_00_4 = {3c 61 20 68 72 65 66 3d 22 69 70 2e 70 68 70 3f } //01 00  <a href="ip.php?
		$a_00_5 = {4e 54 64 68 63 70 2e 65 78 65 } //01 00  NTdhcp.exe
		$a_00_6 = {4d 41 49 4c 20 46 52 4f 4d 3a 20 3c } //01 00  MAIL FROM: <
		$a_00_7 = {52 43 50 54 20 54 4f 3a 20 3c } //01 00  RCPT TO: <
		$a_00_8 = {43 61 6c 6c 4e 65 78 74 48 6f 6f 6b 45 78 } //01 00  CallNextHookEx
		$a_00_9 = {5c 45 78 70 6c 6f 72 65 72 5c 53 68 65 6c 6c 45 78 65 63 75 74 65 48 6f 6f 6b 73 } //01 00  \Explorer\ShellExecuteHooks
		$a_00_10 = {5c 52 65 63 6f 76 65 72 79 20 47 65 6e 69 75 73 20 32 31 73 74 } //01 00  \Recovery Genius 21st
		$a_00_11 = {61 70 70 6c 69 63 61 74 69 6f 6e 2f 78 2d 77 77 77 2d 66 6f 72 6d 2d } //01 00  application/x-www-form-
		$a_00_12 = {50 65 72 73 6f 6e 61 6c 20 46 69 72 65 57 61 6c 6c } //01 00  Personal FireWall
		$a_00_13 = {72 69 73 69 6e 67 5c 52 61 76 } //01 00  rising\Rav
		$a_00_14 = {54 65 6e 63 65 6e 74 5c 51 51 } //01 00  Tencent\QQ
		$a_01_15 = {4a 75 6d 70 48 6f 6f 6b 4f 6e } //01 00  JumpHookOn
		$a_00_16 = {2e 71 71 2e 63 6f 6d 2f 63 6c 69 65 6e 74 75 72 6c 5f 73 69 6d 70 5f 31 39 } //01 00  .qq.com/clienturl_simp_19
		$a_00_17 = {2e 71 71 2e 63 6f 6d 2f 63 67 69 2d 62 69 6e 2f 61 66 74 65 72 5f 6c 6f 67 6f 6e } //00 00  .qq.com/cgi-bin/after_logon
	condition:
		any of ($a_*)
 
}