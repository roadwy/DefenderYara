
rule HackTool_Linux_Cymothoa_A_MTB{
	meta:
		description = "HackTool:Linux/Cymothoa.A!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {69 6e 6a 65 63 74 69 6e 67 20 63 6f 64 65 20 69 6e 74 6f 20 30 78 25 2e 38 78 } //1 injecting code into 0x%.8x
		$a_00_1 = {63 79 6d 6f 74 68 6f 61 20 2d 70 20 3c 70 69 64 3e 20 2d 73 20 3c 73 68 65 6c 6c 63 6f 64 65 5f 6e 75 6d 62 65 72 } //1 cymothoa -p <pid> -s <shellcode_number
		$a_00_2 = {52 75 6e 74 69 6d 65 20 73 68 65 6c 6c 63 6f 64 65 20 69 6e 6a 65 63 74 69 6f 6e 2c 20 66 6f 72 20 73 74 65 61 6c 74 68 79 20 62 61 63 6b 64 6f 6f 72 73 } //1 Runtime shellcode injection, for stealthy backdoors
		$a_00_3 = {78 65 6e 6f 6d 75 74 61 2e 74 75 78 66 61 6d 69 6c 79 2e 6f 72 67 } //1 xenomuta.tuxfamily.org
		$a_00_4 = {61 75 64 69 6f 20 28 6b 6e 6f 63 6b 20 6b 6e 6f 63 6b 20 6b 6e 6f 63 6b 29 20 76 69 61 20 2f 64 65 76 2f 64 73 70 } //1 audio (knock knock knock) via /dev/dsp
		$a_00_5 = {61 6c 61 72 6d 28 29 20 62 61 63 6b 64 6f 6f 72 20 28 72 65 71 75 69 72 65 73 20 2d 6a 20 2d 79 29 20 62 69 6e 64 20 70 6f 72 74 2c 20 66 6f 72 6b 20 6f 6e 20 61 63 63 65 70 74 } //1 alarm() backdoor (requires -j -y) bind port, fork on accept
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}