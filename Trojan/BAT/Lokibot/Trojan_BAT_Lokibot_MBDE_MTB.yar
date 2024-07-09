
rule Trojan_BAT_Lokibot_MBDE_MTB{
	meta:
		description = "Trojan:BAT/Lokibot.MBDE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {38 d5 01 00 00 06 07 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 6f ?? 00 00 06 28 ?? 00 00 06 5a 02 7b ?? 00 00 04 08 6f ?? 00 00 0a 6f ?? 00 00 06 } //1
		$a_01_1 = {62 34 62 38 32 61 32 66 2d 64 63 33 34 2d 34 61 61 39 2d 62 32 33 37 2d 64 33 30 31 37 65 63 38 62 65 65 65 } //1 b4b82a2f-dc34-4aa9-b237-d3017ec8beee
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}