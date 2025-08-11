
rule Trojan_Win32_LummaStealer_DIZ_MTB{
	meta:
		description = "Trojan:Win32/LummaStealer.DIZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 f3 0f b6 5c 34 04 01 d3 00 db 80 f3 55 89 d9 d0 e9 00 d9 88 d5 0f b6 f1 80 e5 0f 32 2c 17 8d 1c 76 30 dd 88 2c 17 8b 8c 24 ?? ?? ?? ?? 42 39 d1 0f 85 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}