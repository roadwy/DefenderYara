
rule Trojan_Win32_Mokes_PVA_MTB{
	meta:
		description = "Trojan:Win32/Mokes.PVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? c1 e8 10 25 ff 7f 00 00 c3 90 09 05 00 a1 } //1
		$a_02_1 = {30 04 11 41 3b 4d 08 7c 90 09 05 00 e8 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}