
rule Trojan_Win32_Enchanim_gen_B{
	meta:
		description = "Trojan:Win32/Enchanim.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {39 45 0c 74 0d 83 c6 04 47 ff 4d fc 75 df 31 c0 eb 1d 8b 55 f8 8b 42 24 03 45 08 0f b7 3c 78 8b 72 1c 03 75 08 8b 04 be 85 c0 74 03 03 45 08 ed } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}