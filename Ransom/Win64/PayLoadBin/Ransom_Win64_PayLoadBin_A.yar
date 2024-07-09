
rule Ransom_Win64_PayLoadBin_A{
	meta:
		description = "Ransom:Win64/PayLoadBin.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 c7 44 24 38 ff ff ff ff c7 44 24 30 59 dc 00 00 8b 05 ?? ?? ?? ?? 89 44 24 4c 48 8b ?? ?? ?? ?? ?? 48 89 44 24 40 b9 02 00 00 00 ff ?? ?? ?? 8b 44 24 30 2d 19 dc 00 00 89 44 24 20 41 b9 00 30 00 00 44 8b 44 24 4c 33 d2 48 8b 4c 24 38 ff [0-3c] 48 8d 84 01 20 73 1c 00 } //4
		$a_00_1 = {7b 61 61 35 62 36 61 38 30 2d 62 38 33 34 2d 31 31 64 30 2d 39 33 32 66 2d 30 30 61 30 63 39 30 64 63 61 61 39 7d } //1 {aa5b6a80-b834-11d0-932f-00a0c90dcaa9}
	condition:
		((#a_03_0  & 1)*4+(#a_00_1  & 1)*1) >=5
 
}