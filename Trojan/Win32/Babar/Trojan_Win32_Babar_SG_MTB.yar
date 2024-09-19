
rule Trojan_Win32_Babar_SG_MTB{
	meta:
		description = "Trojan:Win32/Babar.SG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {a1 28 4f 42 00 33 c5 50 ff 75 fc c7 45 fc ff ff ff ff 8d 45 f4 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}