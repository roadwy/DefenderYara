
rule Trojan_Win64_DuckTail_GTT_MTB{
	meta:
		description = "Trojan:Win64/DuckTail.GTT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {b5 95 00 d9 95 28 41 8f 69 8f ?? ?? ?? ?? b5 92 1d 96 55 96 25 93 65 92 ed 92 8d 92 } //10
		$a_01_1 = {41 00 50 00 45 00 58 00 5f 00 54 00 4d 00 48 00 75 00 70 00 64 00 61 00 74 00 69 00 6e 00 67 00 64 00 69 00 73 00 61 00 62 00 6c 00 65 00 64 00 6b 00 65 00 79 00 5f 00 6e 00 6f 00 74 00 5f 00 6f 00 74 00 5f 00 66 00 6f 00 75 00 6e 00 64 00 } //1 APEX_TMHupdatingdisabledkey_not_ot_found
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1) >=11
 
}