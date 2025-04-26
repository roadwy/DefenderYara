
rule Trojan_BAT_AgentTesla_PNE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 04 00 00 "
		
	strings :
		$a_01_0 = {45 00 62 00 76 00 73 00 4f 00 43 00 63 00 4f 00 42 00 5a 00 68 00 7a 00 71 00 61 00 48 00 } //5 EbvsOCcOBZhzqaH
		$a_00_1 = {24 63 34 32 39 35 38 31 35 2d 66 63 63 34 2d 34 33 30 37 2d 39 35 65 32 2d 66 39 36 39 31 62 63 37 66 62 65 33 } //2 $c4295815-fcc4-4307-95e2-f9691bc7fbe3
		$a_00_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
		$a_00_3 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*5+(#a_00_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=9
 
}