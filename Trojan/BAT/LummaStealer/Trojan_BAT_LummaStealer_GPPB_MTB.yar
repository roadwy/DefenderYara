
rule Trojan_BAT_LummaStealer_GPPB_MTB{
	meta:
		description = "Trojan:BAT/LummaStealer.GPPB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {54 6d 35 4d 63 59 53 43 78 48 72 47 69 34 53 2b 78 73 30 64 52 4b 78 79 2b 38 2f 4f 4b 78 52 4e 58 78 31 53 45 50 51 45 49 38 30 34 44 7a 34 59 38 50 75 6e 46 61 6e 67 } //1 Tm5McYSCxHrGi4S+xs0dRKxy+8/OKxRNXx1SEPQEI804Dz4Y8PunFang
	condition:
		((#a_01_0  & 1)*1) >=1
 
}