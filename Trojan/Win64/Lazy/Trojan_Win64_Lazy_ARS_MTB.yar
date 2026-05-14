
rule Trojan_Win64_Lazy_ARS_MTB{
	meta:
		description = "Trojan:Win64/Lazy.ARS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0c 0a ff c2 41 30 48 ?? 48 8b cf 8b c2 48 3b 05 ?? ?? ?? ?? 0f 44 d6 48 83 3d } //6
		$a_81_1 = {45 78 65 63 75 74 69 6e 67 20 74 68 65 20 70 61 79 6c 6f 61 64 20 77 69 74 68 20 56 45 48 20 41 53 4d 20 64 65 63 72 79 70 74 69 6f 6e 2e 2e 2e 20 54 68 69 73 20 6d 61 79 20 74 61 6b 65 20 61 20 77 68 69 6c 65 20 64 65 70 65 6e 64 69 6e 67 20 6f 6e 20 74 68 65 20 65 66 66 69 63 69 65 6e 63 79 20 6f 66 20 74 68 65 20 73 68 65 6c 6c 63 6f 64 65 2e 2e 2e } //14 Executing the payload with VEH ASM decryption... This may take a while depending on the efficiency of the shellcode...
	condition:
		((#a_03_0  & 1)*6+(#a_81_1  & 1)*14) >=20
 
}