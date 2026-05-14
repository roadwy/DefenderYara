
rule Trojan_Win64_Rootkit_LM_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.LM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 8b 11 45 33 d2 49 03 d0 eb ?? 41 c1 ca 0d 0f be c0 44 03 d0 48 ff c2 8a 02 84 c0 75 ?? 44 3b d6 74 1e ff c3 49 83 c1 04 48 83 c1 02 } //20
		$a_01_1 = {48 63 48 3c 33 db 44 8b 9c 01 88 00 00 00 45 8b 4c 03 20 41 8b 4c 03 24 4c 03 c8 48 03 c8 41 39 5c 03 18 } //10
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*10) >=30
 
}