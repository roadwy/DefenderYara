
rule Trojan_Win32_Ursnif_X_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.X!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 03 0a 0f b7 d9 0f af c3 03 c7 66 3b 0d } //2
		$a_01_1 = {f6 eb 49 8a d9 2a d8 8a c3 8a 1c 2e 88 1e 0f b6 d8 2b df 46 8d 54 1a } //2
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}