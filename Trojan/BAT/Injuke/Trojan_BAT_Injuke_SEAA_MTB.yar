
rule Trojan_BAT_Injuke_SEAA_MTB{
	meta:
		description = "Trojan:BAT/Injuke.SEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 00 2e 00 69 00 2e 00 72 00 2e 00 74 00 2e 00 75 00 2e 00 61 00 2e 00 6c 00 2e 00 41 00 2e 00 6c 00 2e 00 6c 00 2e 00 6f 00 2e 00 63 00 } //2 V.i.r.t.u.a.l.A.l.l.o.c
		$a_01_1 = {56 00 2e 00 69 00 2e 00 72 00 2e 00 74 00 2e 00 75 00 2e 00 61 00 2e 00 6c 00 2e 00 50 00 2e 00 72 00 2e 00 6f 00 2e 00 74 00 2e 00 65 00 2e 00 63 00 2e 00 74 00 } //3 V.i.r.t.u.a.l.P.r.o.t.e.c.t
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}