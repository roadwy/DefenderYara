
rule Ransom_Win32_ContiCrypt_PI_MTB{
	meta:
		description = "Ransom:Win32/ContiCrypt.PI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 8b ec 8b 75 08 8b 7d 0c 8b 55 10 b1 06 ac 90 02 80 32 c1 32 c1 90 02 80 32 c1 32 c1 90 02 20 2a c1 aa 4a 0f 85 90 01 04 8b ec 5d c2 0c 00 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}