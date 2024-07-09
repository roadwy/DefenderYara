
rule DDoS_Win32_Nitol_gen_A{
	meta:
		description = "DDoS:Win32/Nitol.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 85 bc fc ff ff 47 b0 65 88 85 bd fc ff ff c6 85 be fc ff ff 74 c6 85 bf fc ff ff 4d c6 85 c0 fc ff ff 6f c6 85 c1 fc ff ff 64 c6 85 c2 fc ff ff 75 b1 6c } //2
		$a_01_1 = {83 c4 04 83 c0 61 50 6a 1a e8 } //1
		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 2e 65 78 65 00 } //1
		$a_03_3 = {25 75 20 4d 42 90 05 04 01 00 25 75 20 4d 48 7a 90 05 04 01 00 7e 4d 48 7a } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}