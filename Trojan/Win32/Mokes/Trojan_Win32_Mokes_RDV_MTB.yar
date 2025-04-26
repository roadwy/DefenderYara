
rule Trojan_Win32_Mokes_RDV_MTB{
	meta:
		description = "Trojan:Win32/Mokes.RDV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ff 3b de 7e ?? 8b 45 ?? 8d 0c 07 e8 ?? ?? ?? ?? 30 01 83 fb 19 75 ?? 56 56 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}