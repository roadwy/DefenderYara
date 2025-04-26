
rule Trojan_Win32_Copak_KAV_MTB{
	meta:
		description = "Trojan:Win32/Copak.KAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {7c 9a 65 00 [0-14] 70 9c 65 00 [0-28] 81 ?? ff 00 00 00 [0-0f] 31 [0-32] 81 ?? 92 9c 65 00 0f 8c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}