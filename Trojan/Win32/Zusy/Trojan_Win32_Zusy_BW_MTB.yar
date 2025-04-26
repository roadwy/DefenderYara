
rule Trojan_Win32_Zusy_BW_MTB{
	meta:
		description = "Trojan:Win32/Zusy.BW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {99 31 d0 29 d0 89 c2 83 fa ff 0f 93 c0 0f b6 c0 f7 d8 29 c2 } //3
		$a_01_1 = {01 d0 31 cb 89 da 88 10 83 45 } //2
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}