
rule Trojan_BAT_XWormRAT_RP_MTB{
	meta:
		description = "Trojan:BAT/XWormRAT.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6c 69 33 30 37 36 45 4a 51 66 54 47 41 51 50 4f 37 5a 6f 6b 32 6f } //1 li3076EJQfTGAQPO7Zok2o
		$a_01_1 = {45 50 71 66 6f 58 42 57 79 6e 70 51 45 50 6f 67 4a 39 32 71 64 4d 72 6d 39 48 62 76 4e 53 69 67 74 37 71 4f 39 4a 72 } //1 EPqfoXBWynpQEPogJ92qdMrm9HbvNSigt7qO9Jr
		$a_01_2 = {56 54 57 72 31 42 78 49 79 42 79 67 49 49 33 73 71 4b 67 30 77 69 } //1 VTWr1BxIyBygII3sqKg0wi
		$a_01_3 = {65 6b 43 79 4c 50 78 66 39 48 50 58 30 36 44 4b 62 62 4e 4f 42 67 76 6b 6a 61 5a 30 4d 48 42 33 54 59 38 58 39 52 6a } //1 ekCyLPxf9HPX06DKbbNOBgvkjaZ0MHB3TY8X9Rj
		$a_01_4 = {44 34 57 52 53 6e 32 79 34 6e 74 69 67 72 79 41 78 62 58 35 7a 69 33 6e 45 65 59 61 79 44 50 6c 34 4f 32 64 74 5a 6b } //1 D4WRSn2y4ntigryAxbX5zi3nEeYayDPl4O2dtZk
		$a_01_5 = {58 48 4a 59 44 54 77 33 70 6e 59 57 77 58 53 4c 35 6a 4c 69 63 6b } //1 XHJYDTw3pnYWwXSL5jLick
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}