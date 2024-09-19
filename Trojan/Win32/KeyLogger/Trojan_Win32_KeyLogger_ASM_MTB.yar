
rule Trojan_Win32_KeyLogger_ASM_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.ASM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {2d 73 20 2d 77 20 2d 6f 20 73 38 63 6b 78 6a 33 73 2e 65 78 65 20 2d 58 20 27 6d 61 69 6e 2e 42 69 6e 49 44 3d 48 27 20 2d 58 20 27 6d 61 69 6e 2e 63 6f 70 79 3d 54 72 75 65 27 20 2d 58 20 27 6d 61 69 6e 2e 64 6f 6d 61 69 6e 3d 35 69 39 2e 78 79 7a } //5 -s -w -o s8ckxj3s.exe -X 'main.BinID=H' -X 'main.copy=True' -X 'main.domain=5i9.xyz
		$a_01_1 = {52 4c 46 6f 32 45 4c 75 67 75 2d 52 6e 43 70 54 47 70 77 55 2f 79 67 4b 45 68 49 39 32 74 48 57 52 4f 4b 53 53 6d 68 45 39 2f 6f 56 76 49 52 4c 6a 53 72 36 6f 6c 6d 47 6b 69 76 7a 59 32 2f 52 4c 46 6f 32 45 4c 75 67 75 2d 52 6e 43 70 54 47 70 77 55 } //5 RLFo2ELugu-RnCpTGpwU/ygKEhI92tHWROKSSmhE9/oVvIRLjSr6olmGkivzY2/RLFo2ELugu-RnCpTGpwU
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}