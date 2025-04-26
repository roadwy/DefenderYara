
rule SoftwareBundler_Win32_NetPumper{
	meta:
		description = "SoftwareBundler:Win32/NetPumper,SIGNATURE_TYPE_PEHSTR,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {0a 00 4e 65 74 50 75 6d 70 65 72 2f 30 2e 30 00 50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 00 25 73 3a 25 64 00 43 6f 6e 6e 65 63 74 69 6f 6e 3a 20 63 6c 6f 73 65 0d 0a 00 2a 2f 2a 00 25 73 } //5
		$a_01_1 = {00 4e 65 74 50 75 6d 70 65 72 2e 65 78 65 00 59 6f 75 20 6d 75 73 74 20 73 65 6c 65 63 74 20 66 69 6c 65 } //3
		$a_01_2 = {2c 20 4e 65 74 50 75 6d 70 65 72 20 76 } //2 , NetPumper v
		$a_01_3 = {4e 65 74 50 75 6d 70 65 72 2e 41 64 64 55 72 6c } //2 NetPumper.AddUrl
		$a_01_4 = {42 55 49 4c 44 5c 41 4e 54 49 2d 4c 45 45 43 48 5c 4e 65 74 50 75 6d 70 65 72 5c 4e 65 74 50 75 6d 70 65 72 } //2 BUILD\ANTI-LEECH\NetPumper\NetPumper
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*3+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2) >=11
 
}