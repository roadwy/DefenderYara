
rule Ransom_Win32_StopCrypt_SSH_MTB{
	meta:
		description = "Ransom:Win32/StopCrypt.SSH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4c 24 38 8d 44 24 ?? 89 54 24 28 e8 28 fe ff ff 8b 44 24 24 31 44 24 14 81 3d 0c 02 55 02 21 01 00 00 75 ?? 53 53 53 ff 15 ?? ?? ?? ?? 8b 44 24 14 33 44 24 28 81 c7 ?? ?? ?? ?? 2b f0 83 6c 24 34 01 89 44 24 14 89 7c 24 2c 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}