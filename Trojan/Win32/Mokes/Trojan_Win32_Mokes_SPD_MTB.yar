
rule Trojan_Win32_Mokes_SPD_MTB{
	meta:
		description = "Trojan:Win32/Mokes.SPD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 4c 24 0c 30 04 31 83 ff 0f 75 } //4
	condition:
		((#a_01_0  & 1)*4) >=4
 
}