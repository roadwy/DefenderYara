
rule Trojan_Win64_Vidar_MCP_MTB{
	meta:
		description = "Trojan:Win64/Vidar.MCP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {32 72 38 32 6f 59 31 74 69 4a 46 33 6a 55 58 44 79 78 6a 72 2f 62 6b 33 4f 78 67 57 47 64 63 6d } //1 2r82oY1tiJF3jUXDyxjr/bk3OxgWGdcm
		$a_01_1 = {43 61 4c 62 77 5f 59 48 48 6f 47 7a 6a 2d 30 4e 34 79 71 70 2f 2d 5f 6e 78 54 6c 38 6d 35 6a 48 } //1 CaLbw_YHHoGzj-0N4yqp/-_nxTl8m5jH
		$a_01_2 = {50 55 32 77 78 65 32 55 73 48 79 5f 6f 78 38 4c 55 46 73 58 2f 32 4e 47 71 6c 4f 53 4b 2d 4e 6b } //1 PU2wxe2UsHy_ox8LUFsX/2NGqlOSK-Nk
		$a_01_3 = {43 54 2d 6a 72 54 4c 45 78 69 72 48 61 4c 76 4e 35 4e 33 6e 2f 48 52 46 46 46 38 30 66 33 6f 73 } //1 CT-jrTLExirHaLvN5N3n/HRFFF80f3os
		$a_01_4 = {4f 47 6b 56 33 6c 31 66 50 50 36 70 4c 65 4e 4b 33 31 47 38 2f 6f 68 46 69 30 52 63 53 6d 70 44 } //1 OGkV3l1fPP6pLeNK31G8/ohFi0RcSmpD
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}