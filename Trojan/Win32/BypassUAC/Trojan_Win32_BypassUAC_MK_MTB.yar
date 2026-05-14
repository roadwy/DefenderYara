
rule Trojan_Win32_BypassUAC_MK_MTB{
	meta:
		description = "Trojan:Win32/BypassUAC.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,2d 00 2d 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 54 55 32 4c 6a 49 7a 4e 43 34 31 4f 43 34 78 4f 54 51 3d } //15 MTU2LjIzNC41OC4xOTQ=
		$a_01_1 = {55 56 68 61 61 47 4d 7a 55 6c 52 6b 62 55 31 31 57 6c 68 6f 62 41 3d 3d } //10 UVhaaGMzUlRkbU11WlhobA==
		$a_01_2 = {54 58 70 5a 64 32 52 49 53 6d 68 6c 55 7a 56 73 5a 55 64 56 50 51 3d 3d } //10 TXpZd2RISmhlUzVsZUdVPQ==
		$a_81_3 = {44 65 43 6f 6e 68 6f 73 74 2e 65 78 65 } //5 DeConhost.exe
		$a_01_4 = {73 74 61 72 74 6d 6f 6e 69 74 6f 72 6e 6f 6b 69 6c 6c } //3 startmonitornokill
		$a_81_5 = {46 61 69 6c 65 64 20 74 6f 20 77 72 69 74 65 20 73 68 65 6c 6c 63 6f 64 65 20 74 6f 20 66 69 6c 65 2e } //2 Failed to write shellcode to file.
	condition:
		((#a_01_0  & 1)*15+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_81_3  & 1)*5+(#a_01_4  & 1)*3+(#a_81_5  & 1)*2) >=45
 
}