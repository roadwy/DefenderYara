
rule Ransom_Win32_Genasom_FF{
	meta:
		description = "Ransom:Win32/Genasom.FF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c6 84 05 f1 fe ff ff 3e c6 84 05 f3 fe ff ff 6e c6 84 05 f4 fe ff ff 75 c6 84 05 f5 fe ff ff 6c } //1
		$a_01_1 = {c7 85 a4 fc ff ff 53 65 74 50 c7 85 a8 fc ff ff 72 6f 63 65 c7 85 ac fc ff ff 73 73 50 72 c7 85 b0 fc ff ff 69 6f 72 69 c7 85 b4 fc ff ff 74 79 42 6f c7 85 b8 fc ff ff 6f 73 74 00 } //1
		$a_03_2 = {ff ff 54 00 61 00 c7 85 ?? ?? ff ff 73 00 6b 00 c7 85 ?? ?? ff ff 6d 00 67 00 c7 85 ?? ?? ff ff 72 00 2e 00 c7 85 ?? ?? ff ff 65 00 78 00 c7 85 ?? ?? ff ff 65 00 00 00 } //1
		$a_01_3 = {b8 6c 00 00 00 66 89 85 54 fc ff ff b9 6c 00 00 00 66 89 8d 56 fc ff ff ba 20 00 00 00 66 89 95 58 fc ff ff b8 2f 00 00 00 66 89 85 5a fc ff ff b9 46 00 00 00 66 89 8d 5c fc ff ff ba 20 00 00 00 66 89 95 5e fc ff ff b8 2f 00 00 00 66 89 85 60 fc ff ff b9 49 00 00 00 66 89 8d 62 fc ff ff ba 4d 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}