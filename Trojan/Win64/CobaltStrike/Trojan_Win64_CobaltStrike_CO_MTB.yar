
rule Trojan_Win64_CobaltStrike_CO_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.CO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {0f b6 14 08 f7 d2 88 14 08 48 ff c1 48 39 cb 7f ef } //1
		$a_01_1 = {41 37 64 38 47 77 38 58 4e 2f 2f 2f 2f 37 36 75 76 71 2b 74 72 71 6d 33 7a 69 32 61 74 33 53 74 6e 37 64 30 72 65 65 33 64 4b 33 66 74 33 53 4e 72 37 66 77 53 4c 57 31 73 73 34 32 74 38 34 2f 55 } //1 A7d8Gw8XN////76uvq+trqm3zi2at3Stn7d0ree3dK3ft3SNr7fwSLW1ss42t84/U
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}