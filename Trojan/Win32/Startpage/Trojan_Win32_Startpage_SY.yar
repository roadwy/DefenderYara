
rule Trojan_Win32_Startpage_SY{
	meta:
		description = "Trojan:Win32/Startpage.SY,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {25 77 25 77 25 77 2e 30 38 25 31 38 34 25 31 39 2e 25 63 25 6f 25 6d } //01 00  %w%w%w.08%184%19.%c%o%m
		$a_01_1 = {4d 79 53 74 61 72 74 4a 53 4e 61 6d 65 } //01 00  MyStartJSName
		$a_01_2 = {5c 41 64 6f 62 65 5c 41 64 6f 62 65 20 55 74 69 6c 69 74 69 65 73 5c 45 78 74 65 6e 64 53 63 72 69 70 74 20 54 6f 6f 6c 6b 69 74 20 43 53 34 } //01 00  \Adobe\Adobe Utilities\ExtendScript Toolkit CS4
		$a_01_3 = {67 6f 74 6f 20 20 20 74 72 79 } //01 00  goto   try
		$a_01_4 = {77 77 77 2e 38 32 30 31 39 2e 63 6f 6d } //00 00  www.82019.com
	condition:
		any of ($a_*)
 
}