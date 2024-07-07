
rule Trojan_BAT_Stealc_MBJH_MTB{
	meta:
		description = "Trojan:BAT/Stealc.MBJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 66 73 64 6b 66 64 64 67 66 67 66 66 73 65 66 61 66 63 68 64 } //1 hfsdkfddgfgffsefafchd
		$a_01_1 = {63 66 66 66 66 64 61 64 66 64 72 73 66 73 73 68 64 6b 66 66 66 67 68 } //1 cffffdadfdrsfsshdkfffgh
		$a_01_2 = {66 73 66 66 66 66 64 64 64 66 67 66 65 66 64 66 6b 66 67 68 6a } //1 fsffffdddfgfefdfkfghj
		$a_01_3 = {73 67 61 66 67 66 64 76 } //1 sgafgfdv
		$a_01_4 = {67 64 66 67 64 32 64 66 73 66 76 66 67 64 66 64 6a } //1 gdfgd2dfsfvfgdfdj
		$a_01_5 = {68 64 66 66 68 68 64 66 68 64 67 67 66 68 64 66 68 64 66 68 64 66 68 64 61 73 66 66 66 66 6b 64 66 } //1 hdffhhdfhdggfhdfhdfhdfhdasffffkdf
		$a_01_6 = {52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 } //1 RijndaelManaged
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}