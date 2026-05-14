
rule Trojan_Win64_Rootkit_SXA_MTB{
	meta:
		description = "Trojan:Win64/Rootkit.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 1e 00 02 00 00 "
		
	strings :
		$a_03_0 = {41 0f b7 c1 48 8d 0c 80 41 8b 54 ca ?? 45 8b 44 ca ?? 48 03 d3 41 8b 44 ca ?? 4d 03 c6 85 c0 74 ?? 8b c8 0f 1f 40 ?? 66 0f 1f 84 } //20
		$a_03_1 = {48 8b 17 48 85 d2 79 ?? 48 63 46 ?? 0f b7 d2 8b 8c 30 ?? ?? ?? ?? 8b 44 31 ?? 8b 4c 31 ?? 48 2b d0 48 03 ce 8b 04 91 48 03 c6 eb } //10
	condition:
		((#a_03_0  & 1)*20+(#a_03_1  & 1)*10) >=30
 
}