
rule Trojan_Win32_Ursnif_VA_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.VA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 4c 00 fb 0f af c8 81 c6 10 58 08 01 89 b4 2f 84 f2 ff ff 8b 2d 90 01 04 83 c7 04 03 cd 81 ff 54 0e 00 00 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}