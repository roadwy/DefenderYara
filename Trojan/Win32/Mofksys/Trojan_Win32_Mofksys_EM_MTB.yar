
rule Trojan_Win32_Mofksys_EM_MTB{
	meta:
		description = "Trojan:Win32/Mofksys.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {c1 e9 02 31 02 83 c2 04 49 0f 85 f4 ff ff ff 5d c2 0c } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}