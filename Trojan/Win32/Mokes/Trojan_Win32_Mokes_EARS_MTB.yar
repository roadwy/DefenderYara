
rule Trojan_Win32_Mokes_EARS_MTB{
	meta:
		description = "Trojan:Win32/Mokes.EARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 cf 33 ce c7 05 ?? ?? ?? ?? ff ff ff ff 2b d9 8b 44 24 28 29 44 24 10 83 6c 24 14 01 } //5
	condition:
		((#a_02_0  & 1)*5) >=5
 
}