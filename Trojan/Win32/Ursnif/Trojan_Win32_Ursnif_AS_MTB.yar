
rule Trojan_Win32_Ursnif_AS_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c8 0f af 0d 90 01 04 e8 90 01 02 ff ff 05 90 01 04 03 c1 6a 00 a3 90 00 } //1
		$a_02_1 = {0f be 1c 1e e8 90 01 02 ff ff 32 c3 8b 5d 90 01 01 88 04 1e 46 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}