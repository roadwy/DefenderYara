
rule Ransom_Win32_MockCrypter_PA_MTB{
	meta:
		description = "Ransom:Win32/MockCrypter.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {45 78 65 63 75 74 69 6e 67 20 61 20 4d 6f 63 6b 20 52 61 6e 73 6f 6d 77 61 72 65 2e 2e 2e 2e 2e } //1 Executing a Mock Ransomware.....
		$a_01_1 = {77 77 77 2e 6d 61 6b 75 70 30 30 30 30 2e 63 6f 6d } //1 www.makup0000.com
		$a_01_2 = {5c 40 20 50 6c 65 61 73 65 5f 52 65 61 64 5f 4d 65 20 40 20 2e 74 78 74 } //1 \@ Please_Read_Me @ .txt
		$a_81_3 = {59 6f 75 72 20 66 69 6c 65 73 20 61 72 65 20 65 6e 63 72 79 70 74 65 64 } //1 Your files are encrypted
		$a_03_4 = {5c 4d 6f 63 6b 52 61 6e 73 6f 6d 65 77 61 72 65 5c 90 02 10 5c 4d 6f 63 6b 52 61 6e 73 6f 6d 65 77 61 72 65 2e 70 64 62 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_81_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}