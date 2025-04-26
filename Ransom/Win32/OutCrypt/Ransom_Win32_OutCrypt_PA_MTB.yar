
rule Ransom_Win32_OutCrypt_PA_MTB{
	meta:
		description = "Ransom:Win32/OutCrypt.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_02_0 = {83 7d d8 10 7d ?? 8b ?? ?? 8b ?? ?? 8b ?? ?? 8a 0c 1a 8b ?? ?? c1 e6 04 03 ?? ?? 8b ?? ?? 8b ?? ?? 30 ?? ?? ff 45 ?? eb } //3
		$a_00_1 = {61 73 20 62 65 65 6e 20 65 6e 63 72 79 70 74 65 64 } //1 as been encrypted
		$a_00_2 = {48 45 53 4f 59 41 4d 41 45 5a 41 4b 4d 49 52 49 50 41 5a 48 41 48 45 53 4f 59 41 4d 41 45 5a 41 4b 4d 49 52 49 50 41 5a 48 41 } //1 HESOYAMAEZAKMIRIPAZHAHESOYAMAEZAKMIRIPAZHA
		$a_00_3 = {5f 6f 75 74 } //1 _out
		$a_00_4 = {3d 3d 3d 20 42 79 70 61 73 73 65 64 20 3d 3d 3d } //1 === Bypassed ===
	condition:
		((#a_02_0  & 1)*3+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}