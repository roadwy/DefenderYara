
rule Trojan_Win32_CryptInject_AD_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {63 6f 76 65 72 5c 74 68 6f 75 73 61 6e 64 5c 4d 65 61 6e 5c 44 65 61 74 68 5c 42 75 69 6c 64 5c 52 65 61 63 68 5c 42 65 6c 69 65 76 65 5c 63 6f 61 73 74 64 72 61 77 2e 70 64 62 } //1 cover\thousand\Mean\Death\Build\Reach\Believe\coastdraw.pdb
	condition:
		((#a_01_0  & 1)*1) >=1
 
}