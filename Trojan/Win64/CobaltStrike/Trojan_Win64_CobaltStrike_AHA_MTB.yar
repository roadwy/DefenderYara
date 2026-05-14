
rule Trojan_Win64_CobaltStrike_AHA_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AHA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 89 c8 b9 ?? 00 00 00 f3 a4 48 39 d0 74 ?? 48 89 c1 83 e1 1f 8a 4c 0c 0f 41 30 0c 00 48 ff c0 eb } //30
		$a_01_1 = {73 74 61 72 74 20 2f 6d 69 6e 20 22 22 20 72 65 67 73 76 72 33 32 20 2f 73 20 22 25 73 } //20 start /min "" regsvr32 /s "%s
	condition:
		((#a_03_0  & 1)*30+(#a_01_1  & 1)*20) >=50
 
}