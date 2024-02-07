
rule Trojan_BAT_AgentTesla_NBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {23 66 73 61 6c 6c 75 69 69 6a 75 69 64 73 78 66 73 64 66 66 66 73 64 66 64 73 66 68 66 61 73 61 66 2e 64 6c 6c 23 } //01 00  #fsalluiijuidsxfsdfffsdfdsfhfasaf.dll#
		$a_01_1 = {23 66 61 73 76 78 66 64 73 66 73 64 66 66 66 61 66 67 73 64 64 64 64 64 6f 6b 75 69 6a 6f 75 69 6c 70 6f 64 64 64 64 73 73 61 66 2e 64 6c 6c 23 } //01 00  #fasvxfdsfsdfffafgsdddddokuijouilpoddddssaf.dll#
		$a_01_2 = {23 69 6a 66 61 6b 6b 67 66 66 73 66 76 78 64 73 66 73 67 6b 2e 64 6c 6c 23 } //01 00  #ijfakkgffsfvxdsfsgk.dll#
		$a_01_3 = {6b 23 61 66 73 66 66 61 73 66 61 23 } //01 00  k#afsffasfa#
		$a_01_4 = {46 72 6f 6d 42 61 73 65 36 34 } //01 00  FromBase64
		$a_01_5 = {47 65 74 4d 65 74 68 6f 64 } //00 00  GetMethod
	condition:
		any of ($a_*)
 
}