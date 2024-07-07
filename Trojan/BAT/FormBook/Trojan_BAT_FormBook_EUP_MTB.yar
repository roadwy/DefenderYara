
rule Trojan_BAT_FormBook_EUP_MTB{
	meta:
		description = "Trojan:BAT/FormBook.EUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {db f9 ec 90 2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 ba 35 db f9 ec 90 2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 ba 35 db f9 ec 90 } //1
		$a_01_1 = {3a 6d 74 62 df 91 62 6b 88 38 f4 da a6 1e 4c 52 01 4f 50 71 99 fc 44 7d 05 77 6c 4e 66 4b 9a 3e 81 20 ac 6f 4a dc 79 d0 f9 b5 84 5c 10 c1 cb 95 } //1
		$a_01_2 = {2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 bb 37 c4 c1 e8 90 2c c0 df b1 3e 4b 3c 38 cc bb 40 2d 4a 4b 22 b1 ba 35 db f9 ec 90 2c c0 df b1 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}