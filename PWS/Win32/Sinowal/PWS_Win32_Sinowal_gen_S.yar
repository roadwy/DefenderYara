
rule PWS_Win32_Sinowal_gen_S{
	meta:
		description = "PWS:Win32/Sinowal.gen!S,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 52 65 61 6c 48 61 72 64 44 69 73 6b 30 00 00 00 5c 5c 2e 5c 50 68 79 73 69 63 61 6c 44 72 69 76 65 25 64 } //1
		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 66 20 2d 74 20 30 } //1 shutdown -r -f -t 0
		$a_01_2 = {25 53 79 73 74 65 6d 52 6f 6f 74 25 5c 53 79 73 74 65 6d 33 32 5c 44 72 69 76 65 72 73 5c 2a 2e 73 79 73 } //1 %SystemRoot%\System32\Drivers\*.sys
		$a_01_3 = {81 f9 55 aa 00 00 74 07 } //1
		$a_01_4 = {3b f7 75 05 be 4f e6 40 bb } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}