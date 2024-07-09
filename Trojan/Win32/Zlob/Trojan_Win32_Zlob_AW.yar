
rule Trojan_Win32_Zlob_AW{
	meta:
		description = "Trojan:Win32/Zlob.AW,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 c4 10 48 78 16 2b fe 8a 8c 07 ?? ?? ?? ?? 32 4c 24 ?? 48 88 88 ?? ?? ?? ?? 79 ec } //1
		$a_01_1 = {75 11 8d 84 24 1c 01 00 00 50 55 ff 54 24 1c 85 c0 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}