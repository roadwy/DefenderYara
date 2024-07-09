
rule Trojan_Win32_Sinowal_gen_A{
	meta:
		description = "Trojan:Win32/Sinowal.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 04 eb ?? 80 f1 ?? 88 08 40 8a 08 84 c9 75 } //1
		$a_01_1 = {43 6f 6d 6d 6f 6e 46 69 6c 65 73 44 69 72 00 00 55 8b } //1
		$a_01_2 = {4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 00 } //1 呎䍜牵敲瑮敖獲潩n
	condition:
		((#a_02_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}