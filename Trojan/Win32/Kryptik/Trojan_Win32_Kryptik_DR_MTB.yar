
rule Trojan_Win32_Kryptik_DR_MTB{
	meta:
		description = "Trojan:Win32/Kryptik.DR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb a0 9a c0 5c 81 45 ?? 5c 28 e5 31 81 6d ?? dc 13 2c 04 c1 eb 02 81 45 ?? dc 13 2c 04 25 5b 9e bb 32 81 6d ?? ba f6 28 52 81 e3 21 4b 69 37 81 45 ?? 7a 84 d5 38 81 6d ?? fc 12 12 48 81 45 ?? 3c 85 65 61 81 e3 81 a1 03 37 81 6d ?? 64 d7 c4 16 c1 eb 1f 81 6d ?? ba b9 4f 2c 81 45 ?? 1e 91 14 43 81 45 ?? c0 00 00 00 8a 45 } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}