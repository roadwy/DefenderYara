
rule Trojan_Win32_Zusy_PGS_MTB{
	meta:
		description = "Trojan:Win32/Zusy.PGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {21 86 72 3c bd 47 2b a2 7c 1c b3 63 39 86 72 24 bd 47 33 a2 7c 04 b3 63 31 86 72 2c bd 47 3b a2 7c 0c b3 23 bf 05 fb 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}