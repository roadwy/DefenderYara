
rule Trojan_Win32_Copak_GUF_MTB{
	meta:
		description = "Trojan:Win32/Copak.GUF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 13 41 01 ff 81 c3 04 00 00 00 39 c3 75 ec 81 c7 ?? ?? ?? ?? 01 f1 c3 } //10
		$a_01_1 = {31 3e 81 c6 04 00 00 00 49 49 39 c6 75 ed c3 14 40 00 c3 39 c9 74 } //10
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*10) >=10
 
}