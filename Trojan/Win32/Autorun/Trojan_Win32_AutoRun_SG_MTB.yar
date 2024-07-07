
rule Trojan_Win32_AutoRun_SG_MTB{
	meta:
		description = "Trojan:Win32/AutoRun.SG!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 74 66 6d 6f 6e 2e 65 78 65 } //1 ctfmon.exe
		$a_01_1 = {64 6f 77 6e 30 38 2e 33 33 32 32 2e 6f 72 67 2f 6e 75 6d 2e 61 73 70 } //1 down08.3322.org/num.asp
		$a_01_2 = {5c 77 69 6e 64 6f 77 73 5c 63 75 72 72 65 6e 74 76 65 72 73 69 6f 6e 5c 52 75 6e 4f 6e 63 65 45 78 5c 63 74 66 6d 6f 6e } //1 \windows\currentversion\RunOnceEx\ctfmon
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}