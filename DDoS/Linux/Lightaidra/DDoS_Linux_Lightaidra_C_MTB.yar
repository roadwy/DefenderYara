
rule DDoS_Linux_Lightaidra_C_MTB{
	meta:
		description = "DDoS:Linux/Lightaidra.C!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_00_0 = {51 68 bd f2 04 08 68 4c f9 04 08 e8 ee fc ff ff 58 5a 68 4c f9 04 08 68 4c f9 04 08 e8 dd fc ff ff 5d 58 68 59 fa 04 08 68 59 fa 04 08 e8 cc fc ff ff 5e 5f 68 54 f9 04 08 68 54 f9 04 08 e8 bb fc ff ff 59 5b 68 48 fb 04 08 68 5b f9 04 08 e8 aa fc ff ff 58 5a 68 bd f2 04 08 68 5b f9 04 08 e8 99 fc ff ff 5d 58 68 bd f2 04 08 68 59 fa 04 08 e8 88 fc ff ff 5e 5f 68 61 f9 04 08 68 61 f9 04 08 e8 77 fc ff ff } //2
		$a_00_1 = {8b 54 24 1c 83 c4 10 8b 02 8d 8c 24 9c 04 00 00 c7 00 4a 6f 6b 65 c7 40 04 72 45 70 69 c7 40 08 63 6e 65 73 66 c7 40 0c 73 00 8d 94 24 1c 04 00 00 8d 84 24 1c 05 00 00 89 4c 24 08 89 44 24 04 89 14 24 eb 2c } //1
		$a_01_2 = {67 72 65 65 74 68 } //1 greeth
		$a_01_3 = {67 72 65 69 70 } //1 greip
		$a_01_4 = {78 6d 61 73 } //1 xmas
		$a_01_5 = {73 74 6f 6d 70 } //1 stomp
		$a_01_6 = {75 64 70 62 79 70 61 73 73 } //1 udpbypass
		$a_00_7 = {74 63 70 66 72 61 67 } //1 tcpfrag
		$a_00_8 = {74 63 70 72 61 77 } //1 tcpraw
	condition:
		((#a_00_0  & 1)*2+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1) >=6
 
}