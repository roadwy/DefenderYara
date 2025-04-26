
rule Trojan_Win32_Mokes_EAUD_MTB{
	meta:
		description = "Trojan:Win32/Mokes.EAUD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c7 33 c6 c7 05 ?? ?? ?? ?? ff ff ff ff 2b d8 8b 44 24 1c 29 44 24 10 83 6c 24 14 01 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}