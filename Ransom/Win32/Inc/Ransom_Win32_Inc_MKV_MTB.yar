
rule Ransom_Win32_Inc_MKV_MTB{
	meta:
		description = "Ransom:Win32/Inc.MKV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 "
		
	strings :
		$a_01_0 = {33 f6 8a 44 35 ec 46 30 04 3a 47 3b 7d 08 72 ae } //5
		$a_01_1 = {7e 7e 7e 7e 20 49 4e 43 20 52 61 6e 73 6f 6d 20 7e 7e 7e 7e } //2 ~~~~ INC Ransom ~~~~
		$a_01_2 = {59 6f 75 72 20 64 61 74 61 20 69 73 20 73 74 6f 6c 65 6e 20 61 6e 64 20 65 6e 63 72 79 70 74 65 64 } //2 Your data is stolen and encrypted
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=9
 
}