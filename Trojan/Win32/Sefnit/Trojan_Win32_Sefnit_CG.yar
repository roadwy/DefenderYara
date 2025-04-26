
rule Trojan_Win32_Sefnit_CG{
	meta:
		description = "Trojan:Win32/Sefnit.CG,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {83 fe 10 7c d6 6a 01 e8 ?? ?? ?? ?? 59 33 f6 e8 ?? ?? ?? ?? 6a 63 99 59 f7 f9 } //1
		$a_03_1 = {6a 40 6a 22 bf ?? ?? ?? ?? 57 8d 8d 78 fe ff ff e8 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}