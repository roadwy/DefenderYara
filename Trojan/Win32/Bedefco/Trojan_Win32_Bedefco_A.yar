
rule Trojan_Win32_Bedefco_A{
	meta:
		description = "Trojan:Win32/Bedefco.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {31 32 37 2e 30 2e 30 2e 31 20 75 70 64 61 74 65 2e 65 73 65 74 2e 63 6f 6d } //1 127.0.0.1 update.eset.com
		$a_00_1 = {31 32 37 2e 30 2e 30 2e 31 20 75 70 64 61 74 65 31 30 2e 6c 75 6c 75 73 6f 66 74 2e 63 6f 6d } //1 127.0.0.1 update10.lulusoft.com
		$a_00_2 = {2f 6d 6f 64 75 6c 65 2f 67 6c 61 6d 6f 75 72 } //2 /module/glamour
		$a_00_3 = {64 61 74 61 32 38 2e 73 6f 6d 65 65 2e 63 6f 6d 2f 64 61 74 61 33 32 2e 7a 69 70 } //3 data28.somee.com/data32.zip
		$a_00_4 = {63 61 72 6d 61 36 36 36 2e 62 79 65 74 68 6f 73 74 31 32 2e 63 6f 6d 2f 33 32 2e 68 74 6d 6c } //3 carma666.byethost12.com/32.html
		$a_02_5 = {57 69 6e 64 6f 77 73 20 44 72 69 76 65 72 20 53 65 72 76 69 63 65 00 [0-1e] 00 5c 77 69 6e 69 6e 69 74 2e 65 78 65 00 [0-0f] 20 2d 73 65 72 76 69 63 65 00 [0-3c] 5c 73 79 73 74 65 6d 33 32 5c 78 62 6f 78 2d 73 65 72 76 69 63 65 2e 65 78 65 00 } //3
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*2+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_02_5  & 1)*3) >=3
 
}