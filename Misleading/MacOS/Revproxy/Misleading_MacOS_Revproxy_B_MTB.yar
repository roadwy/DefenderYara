
rule Misleading_MacOS_Revproxy_B_MTB{
	meta:
		description = "Misleading:MacOS/Revproxy.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 3b 66 10 76 30 48 83 ec 18 48 89 6c 24 10 48 8d 6c 24 10 4d 8b 66 20 4d 85 e4 75 2f 48 8b 4a 08 48 89 c3 48 89 c8 e8 54 43 fa ff 48 8b 6c 24 10 48 83 c4 18 c3 48 89 44 24 08 0f 1f 44 00 00 e8 bb be ff ff 48 8b 44 24 08 } //1
		$a_01_1 = {75 42 48 89 44 24 28 48 85 c0 74 21 48 8b 10 48 8b 58 08 0f b6 48 10 0f b6 78 11 48 89 d0 e8 82 15 fa ff 48 8b 6c 24 18 48 83 c4 20 c3 e8 b3 28 fa ff 90 48 89 44 24 08 e8 68 b1 ff ff 48 8b 44 24 08 eb a1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}